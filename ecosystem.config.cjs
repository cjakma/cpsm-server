module.exports = {
  apps: [{
    name: 'cpsm-server',
    cwd: '/home/ubuntu/web-service/cpsm-server',
    script: '/home/ubuntu/web-service/cpsm-server/run-production.sh',
    interpreter: '/usr/bin/bash',
    autorestart: true,
    watch: false,
    max_restarts: 10,
    min_uptime: '5s',
    env: { NODE_ENV: 'production', TZ: 'Asia/Seoul' },
  }],
};
