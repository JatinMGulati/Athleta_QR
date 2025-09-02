import QRCode from 'qrcode';

const url = process.argv[2] || 'https://your-host.example/';
QRCode.toFile('claim-qr.png', url, { width: 400 }, function (err) {
  if (err) {
    console.error('QR error', err);
    process.exit(1);
  }
  console.log('QR saved to claim-qr.png ->', url);
});