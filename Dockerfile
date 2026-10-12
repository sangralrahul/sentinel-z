# Sentinel-Z: runs on any architecture the official Node image supports,
# including IBM Z / LinuxONE (linux/s390x), amd64 and arm64.
#   docker build -t sentinel-z .
#   docker run --rm -p 5173:5173 sentinel-z                       # dashboard
#   docker run --rm -v "$PWD:/data" sentinel-z node cli/sentinel-z.js analyze /data/logs.csv
FROM node:20-alpine
WORKDIR /app
COPY package.json ./
COPY core ./core
COPY cli ./cli
COPY web ./web
COPY data ./data
COPY tests ./tests
COPY index.html vercel.json ./
RUN node --test && addgroup -S app && adduser -S app -G app
USER app
ENV PORT=5173
EXPOSE 5173
CMD ["node", "cli/serve.js"]
