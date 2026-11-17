FROM node:24-alpine AS build

WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.28-alpine AS runtime

RUN sed -i \
      -e '/^user[[:space:]]\+nginx;/d' \
      -e 's|/run/nginx.pid|/tmp/nginx/nginx.pid|' \
      -e '/^pid[[:space:]]\+/a\
lock_file /tmp/nginx/nginx.lock;' \
      /etc/nginx/nginx.conf \
  && printf '%s\n' \
      '    client_body_temp_path /tmp/nginx/client_temp;' \
      '    proxy_temp_path /tmp/nginx/proxy_temp;' \
      '    fastcgi_temp_path /tmp/nginx/fastcgi_temp;' \
      '    uwsgi_temp_path /tmp/nginx/uwsgi_temp;' \
      '    scgi_temp_path /tmp/nginx/scgi_temp;' \
      > /tmp/nginx-runtime.conf \
  && sed -i '/^http {/r /tmp/nginx-runtime.conf' /etc/nginx/nginx.conf \
  && rm /tmp/nginx-runtime.conf \
  && mkdir -p \
      /tmp/nginx/client_temp \
      /tmp/nginx/proxy_temp \
      /tmp/nginx/fastcgi_temp \
      /tmp/nginx/uwsgi_temp \
      /tmp/nginx/scgi_temp \
  && chown -R nginx:nginx /tmp/nginx

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build --chown=nginx:nginx /app/dist /usr/share/nginx/html

USER nginx
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1
