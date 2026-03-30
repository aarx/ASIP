FROM node:18

WORKDIR /app

COPY asm-dashboard/package*.json ./

RUN npm install

COPY asm-dashboard .

CMD ["npm", "start"]
