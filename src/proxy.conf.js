/*
 * Dev-server proxy for the Spring Boot backend.
 *
 * The backend host differs by where `ng serve` runs:
 *   - inside the devcontainer, the backend is on the Docker host -> host.docker.internal
 *   - directly on your machine                                   -> localhost
 *
 * Override with API_TARGET, e.g. `API_TARGET=http://localhost:8080 npm start`.
 */
const target =
  process.env['API_TARGET'] ||
  (process.env['DEVCONTAINER'] ? 'http://host.docker.internal:8080' : 'http://localhost:8080');

module.exports = {
  '/api': {
    target,
    secure: false,
    changeOrigin: true,
    pathRewrite: { '^/api': '' },
    logLevel: 'debug',
  },
};
