# Use ultra-lightweight Node base
FROM node:22-alpine

WORKDIR /app

# Install dependencies first for better caching
COPY package*.json ./
RUN npm install --production

# Copy application source
COPY . .

# AI Studio Standard Port
EXPOSE 3000

# Security: Run as non-root user
USER node

# Production Flags
ENV NODE_ENV=production
ENV TRACKER_API_KEY=""

CMD ["node", "server.js"]
