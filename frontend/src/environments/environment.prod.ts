// API/WS are SAME-ORIGIN (relative) so the app works no matter what host serves it
// — localhost, a private-network IP, a phone, etc. A hardcoded `localhost` here breaks any
// remote client (the browser resolves localhost to itself, not the server).
const wsBase = typeof location !== 'undefined'
  ? `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}`
  : '';

export const environment = {
  production: true,
  apiUrl: '/api',
  wsUrl: `${wsBase}/api/ws`,
  appName: 'DeepVigilance',
  version: '0.1.0',
};
