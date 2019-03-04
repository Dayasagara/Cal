FROM golang:1.11

# Add Maintainer Info
# Set the Current Working Directory inside the container
WORKDIR /go/src/auth

# Copy everything from the current directory to the PWD(Present Working Directory) inside the container
COPY . .

# Download all the dependencies
# https://stackoverflow.com/questions/28031603/what-do-three-dots-mean-in-go-command-line-invocations
RUN go get -d -v ./...

# Install the package
RUN go install -v ./...

# This container exposes port 8000 to the outside world
EXPOSE 8000

# Run the executable
CMD ["auth"]