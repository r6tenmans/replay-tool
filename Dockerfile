# Use a lightweight base image
FROM golang:alpine AS builder

# Set environment variables
ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

# Set working directory
WORKDIR /app

# Copy the project files
COPY . .

# Download dependencies
RUN go mod download

# Build the application
RUN go build -o main .

# Use a smaller image for the final stage
FROM alpine

# Copy the binary from the builder stage
COPY --from=builder /app/main /app/main

# Expose the port on which the application will run
EXPOSE 8080

# Run the API on the exposed port with Swagger documentation enabled
CMD ["/app/main", "--api", "8080", "--swagger"]
