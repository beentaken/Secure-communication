Alice and Bob want to establish a secure communication channel where messages are encrypted with RC4. They need to carry out the following tasks. (1) Establish a shared RC4 session key so that they can use it to encrypt messages. (2) Use the shared key to secure the communication.
The key establishment is done by the mechanism of Diffi-Hellman key exchange. Assume that Alice has a pair of private/public keys (x, Y = gx mod p) and has sent her public key Y to Bob. Bob will generate an ephemeral key pair (r, R = gr mod p) and send R to Alice. In the end, both share the same RC4 key, K = gxr mod p.

The protocol is described as follows:
• Alice runs KeyGen to generate a pair of her private and public keys including all required parameters. These keys and parameters are stored in directory Alice.
• Alice executes Host.
- Host is running and listening to the opened port (you need select a port for your code).
• Bob executes Client.
- Client (Bob) sends a connection request to Host.
- Client is ready and listens to the port.
• Alice sends her public key (including all required parameters) to Bob (Client).
• Upon receiving the public key and parameters from Alice, Bob does the following:
- Generate an ephemeral Diffie-Hellman key pair based on the parameters from Alice.
- Compute the Diffie-Hellman key based on his ephemeral secret key and Alice’s public key.
- Set the Diffie-Hellman key as the shared RC4 key.
- Encrypt a message (say, Hello) using the shared RC4 key.
- Send his ephemeral public key and the encrypted message to Alice.
• Upon receiving the message from Client (Bob), Host (Alice) does the following:
- Generate the Diffie-Hellman key based on her secret key and Bob’s ephemeral public key.
- Set the Diffie-Hellman key as the shared RC4 key.
- Decrypt the message with the RC4 key.
- Print the message on the Host screen.
- Encrypt a message (say, Received Hello) with the RC4 key.
- Send the encrypted message back to Bob.
• Upon receiving the message, Bob does the following.
- Decrypt the message.
- Print the message on the Client screen.
• Now, the secure channel is established.
- Either Alice or Bob can send a message encrypted with the RC4 key. They type the message on their own terminal. The message is encrypted by their code (Host or Client) and sent out.
- The received message is printed on the screen.
- To quit the program, the client should type “exit”.