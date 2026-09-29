FROM node:18

WORKDIR /app

COPY asm-dashboard/package*.json ./

RUN npm ci

COPY asm-dashboard .

CMD ["npm", "start"]
