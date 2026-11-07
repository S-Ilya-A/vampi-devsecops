FROM node:14 AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm install
COPY public ./public
RUN npm run vendor

FROM nginx:1.21
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/public /usr/share/nginx/html
EXPOSE 80
