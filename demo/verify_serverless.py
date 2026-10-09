"""Smoke-test Vercel's entry point with an isolated no-credentials deployment."""
import os
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
os.environ['VERCEL'] = '1'
os.environ['DB_PATH'] = ':memory:'
os.environ['DEMO_MODE'] = '0'
os.environ['FEEDS'] = '0'
os.environ['ONLINE_CHECKS'] = '0'
os.environ.pop('DATABASE_URL', None)
from api.index import app
from fastapi.testclient import TestClient

with TestClient(app) as client:
    health = client.get('/api/health').json()
    assert health['storage'] == 'memory' and not health['demo']
    assert health['shared_reports'] is False
    good = 'upi://pay?pa=shop@ybl&pn=Shop'
    result = client.post('/api/analyze', json={'payload': good, 'intent': 'pay_shop'}).json()
    assert result['verdict'] == 'SAFE'
    assert client.post('/api/analyze', json={'payload': good, 'intent': 'receive'}).json()['verdict'] == 'DANGER'
    shop = client.post('/api/shop/register', json={'payload': good, 'shop_name': 'Shop'}).json()
    assert shop['shop_code'] == ''
    assert client.post('/api/shop/verify', json={'payload': good, 'expected_vpa': shop['vpa']}).json()['match']
    assert not client.post('/api/shop/verify', json={'payload': 'upi://pay?pa=someone@axl&pn=Shop', 'expected_vpa': shop['vpa']}).json()['match']
    assert client.post('/api/report', json={'payload': good}).status_code == 503
    print('PASS: Vercel entry, no filesystem persistence, live-mode defaults, payment/receive analysis, stateless shop match/mismatch, honest reporting availability')
