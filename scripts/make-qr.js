import QRCode from 'qrcode';

const PRODUCTION_URL = 'https://athleta-qr.vercel.app'; // Replace with your stable Vercel URL
QRCode.toFile('claim-qr.png', PRODUCTION_URL, {
  color: {
    dark: '#000',  // QR code color
    light: '#FFF' // Background color
  },
  width: 1000,
  margin: 2,
  errorCorrectionLevel: 'H'
}, function (err) {
  if (err) {
    console.error('QR error', err);
    process.exit(1);
  }
  console.log('QR saved to claim-qr.png ->', url);
});