export const config = {
  runtime: 'edge',
  regions: ['iad1'],
};

import app from '../../api/server.js';

export default async function handler(req) {
  return app(req);
}
