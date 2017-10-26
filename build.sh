# Stop and remove all running containers
docker ps -a | xargs docker rm -f

# Remove all dangling images
# docker images --filter "dangling=true" -q | xargs docker rmi

# Remove all previous versions of the qfpapi
docker images --filter=reference='qfpapi:*' -q | xargs docker rmi

# Build new image
docker build -t qfpapi:1.0.0 .

# Run image
docker run -d --name qfpapi -p 5000:5000 qfpapi:1.0.0
