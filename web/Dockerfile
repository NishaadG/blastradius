FROM node:22-alpine AS build
WORKDIR /app
# Empty = same origin (production behind the reverse proxy). Local compose overrides this.
ARG NEXT_PUBLIC_API=
ENV NEXT_PUBLIC_API=$NEXT_PUBLIC_API
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production PORT=3001 HOSTNAME=0.0.0.0
RUN adduser -D -u 10001 app
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
COPY --from=build /app/public ./public
USER app
EXPOSE 3001
CMD ["node", "server.js"]
