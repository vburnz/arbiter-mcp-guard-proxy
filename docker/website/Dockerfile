FROM nginx:alpine
COPY docs/sphinx/_build/html/ /usr/share/nginx/html/
COPY docker/website/ssl/ /etc/nginx/ssl/
COPY docker/website/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80 443
