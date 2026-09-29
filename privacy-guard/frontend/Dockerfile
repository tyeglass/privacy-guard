# ── Build Stage ──────────────────────────────────────────────────────────────
FROM node:20-alpine AS builder
WORKDIR /app

ARG REACT_APP_API_URL=http://localhost:8080
ENV REACT_APP_API_URL=$REACT_APP_API_URL

COPY package*.json ./
RUN npm ci --silent

COPY . .
RUN npm run build

# ── Runtime (Nginx) ───────────────────────────────────────────────────────────
FROM nginx:alpine AS runtime
COPY --from=builder /app/build /usr/share/nginx/html
COPY docker/nginx-frontend.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
