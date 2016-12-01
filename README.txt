Angelo Olcese
aolcese1@jhu.edu
Used 3 late days

To compile my client you use the following line:
javac -cp ".:javax.json-1.0.4.jar.:javax.json-api-1.0.jar" assignment3.java

To run the client you can use the following command:
java -cp ".:javax.json-1.0.4.jar:javax.json-api-1.0.jar" assignment3 

then there are 4 flags that can be invoked, three of which are mandatory 
(-s, -u, -p), and -w which has no affect on the program.

The client has been tested on the jmessage.server.isi.jhu.edu server port 80.
It can send and recieve messages with different usernames between itself
and the reference client. All of the commands should be fully functional given
proper input. Messages are all sent with the id number 0.
