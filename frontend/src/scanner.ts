// QR decoding: native BarcodeDetector where it exists (Chrome on Android),
// otherwise the ZXing-C++ WASM ponyfill (iOS Safari, desktop). The WASM file is
// self-hosted from /zxing_reader.wasm so scanning works offline.
import { BarcodeDetector as Ponyfill, prepareZXingModule } from "barcode-detector/ponyfill";

prepareZXingModule({
  overrides: {
    locateFile: (path: string, prefix: string) =>
      path.endsWith(".wasm") ? "/zxing_reader.wasm" : prefix + path,
  },
});

type Detector = { detect(src: ImageBitmapSource): Promise<{ rawValue: string }[]> };
let detector: Promise<Detector> | null = null;

export function getDetector(): Promise<Detector> {
  if (!detector) {
    detector = (async () => {
      const Native = (window as any).BarcodeDetector;
      if (Native) {
        try {
          const formats: string[] = await Native.getSupportedFormats();
          if (formats.includes("qr_code")) return new Native({ formats: ["qr_code"] }) as Detector;
        } catch { /* fall through to WASM */ }
      }
      return new Ponyfill({ formats: ["qr_code"] }) as unknown as Detector;
    })();
  }
  return detector;
}

export async function decodeFile(file: File): Promise<string | null> {
  const det = await getDetector();
  const bitmap = await createImageBitmap(file);
  try {
    const codes = await det.detect(bitmap);
    return codes[0]?.rawValue ?? null;
  } finally {
    bitmap.close?.();
  }
}

export class CameraScanner {
  private stream: MediaStream | null = null;
  private running = false;
  private busy = false;
  private generation = 0;

  constructor(private video: HTMLVideoElement, private onCode: (text: string) => void) {}

  async start() {
    const generation = ++this.generation;
    if (!navigator.mediaDevices?.getUserMedia) throw new Error("no-camera-api");
    this.stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: { ideal: "environment" }, width: { ideal: 1280 }, height: { ideal: 720 } },
      audio: false,
    });
    if (generation !== this.generation) {
      this.stream.getTracks().forEach(t => t.stop());
      this.stream = null;
      return;
    }
    this.video.srcObject = this.stream;
    this.video.setAttribute("playsinline", "true");
    this.video.muted = true;
    await this.video.play();
    if (generation !== this.generation) return;
    this.running = true;
    const det = await getDetector();
    const tick = async () => {
      if (!this.running) return;
      if (!this.busy && this.video.readyState >= 2) {
        this.busy = true;
        try {
          const codes = await det.detect(this.video);
          if (codes.length && this.running) {
            this.onCode(codes[0].rawValue);
            this.stop();
            return;
          }
        } catch { /* frame not ready */ }
        this.busy = false;
      }
      setTimeout(tick, 120);
    };
    tick();
  }

  stop() {
    this.generation++;
    this.running = false;
    this.stream?.getTracks().forEach((t) => t.stop());
    this.stream = null;
  }
}
