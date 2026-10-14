FROM node:22-alpine AS build
WORKDIR /app
ARG NEXT_PUBLIC_API=http://localhost:8000
ENV NEXT_PUBLIC_API=$NEXT_PUBLIC_API
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production PORT=3001 HOSTNAME=0.0.0.0
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
COPY --from=build /app/public ./public
EXPOSE 3001
CMD ["node", "server.js"]
