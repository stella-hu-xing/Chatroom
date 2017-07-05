# Chatroom 
First distributed system project of implementing a chatroom for multiple users to communicate with each other.

user manual:

1. use terminal to register and login at the client side
register: run the client.jar with command:  java -jar Client.jar -lp localport -u username
login: run the client.jar with command:  java -jar Client.jar -lp localport -u username -p password

2. use terminal to run the servers
run the server.jar with command(root): java -jar Server.jar -lh localhost -lp localport 
run the server.jar with command(not the root): java -jar Server.jar -lh localhost -lp localport -rh remotehost -rp remoteport -s secretToAuthentication
         
