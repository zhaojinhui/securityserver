# securityserver
a security server
This is a security server, using the most recent authentication, authorization and encryption technology. 

This project is running under Window 8 and it is inplemented by using eclipse.
-------------------------------------------------------------------------------
External library: JCE
-------------------------------------------------------------------------------
First, import this project into eclipse.
Second, choose run as application and run the Chatserver first and then run ChatClient.
Third, the pre-figured user information are in the ChatServer.java file.For example: David/12345, Jim/23456, Kate/34567, etc.
Fourth, in command line of client, type the username first and then there will be instructions for user to enter the password.
Fifth, run another client and enter another client's username/password to make sure that there are at least two users in the system.
Sixth, enter "list" to show the on line user list.
Seventh, input a username who you want to talk to.
Eighth, input "send USER¡¡MESSAGE" to another user.
Nineth, if another user want to send message back, he also need to do steps from six to eight.
Tenth, if a user want to log off, input "leave".
-------------------------------------------------------------------------------
Function implement:
Login/log off, authentication/chat/multiple chat, AES, DH and SHA-1.
-------------------------------------------------------------------------------
For more details about the protocol, please see the protocol.ppt. 
