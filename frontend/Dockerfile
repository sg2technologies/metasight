# MetaSight frontend — dev-oriented image (used by ../docker-compose.yml):
# runs the Vite dev server with HMR against a bind-mounted source tree, the
# same experience `npm run dev` gives you outside Docker. Not a production
# image — a production build is just `npm run build`, served by whatever
# static host/CDN/nginx you already run in front of the API (see
# ../DEPLOYMENT.md, section 10).
FROM node:20-slim

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .

EXPOSE 3000

CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "3000"]
