FROM node:14 AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm install
COPY public ./public
RUN npm run vendor

# Was nginx:1.21 (Debian 11.3, 164 High/Critical vulnerabilities with fixes, and
# running as root: Trivy AVD-DS-0002). The unprivileged image runs as user nginx
# (uid 101) and listens on 8080.
FROM nginxinc/nginx-unprivileged:1.30.6-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/public /usr/share/nginx/html
USER 101
EXPOSE 8080
