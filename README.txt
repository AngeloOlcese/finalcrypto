Angelo Olcese
aolcese1@jhu.edu
Used 3 late days

To compile my client you use the following line:
javac -cp ".:javax.json-1.0.4.jar.:javax.json-api-1.0.jar" assignment3.java

To run the client you can use the following command:
java -cp ".:javax.json-1.0.4.jar:javax.json-api-1.0.jar" assignment3 -p 80 -s localhost -u bob


The program takes about 15 minutes to run fully so I have run it once and exported the exact
output to the file output.txt. I started by signing in as Bob and taking his messages before
he go to read them. Once I had a message sent from Alice to Bob, I registered a key as the 
user "A". I then took the message Alice sent and mauled the second byte of the ciphertext 
and sent it to Bob. Once he gave me a read receipt, I know that I had successfully mauled the
message such that the first two letters of plaintext were "A:". After this, I executed
a padding oracle attack using the pkcs padding and read receipts  until I was able
to decrypt the entire message.
