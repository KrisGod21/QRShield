// Self-host the ZXing WASM decoder so scanning works offline and without a CDN.
import { copyFileSync } from "node:fs";
copyFileSync("node_modules/zxing-wasm/dist/reader/zxing_reader.wasm", "public/zxing_reader.wasm");
