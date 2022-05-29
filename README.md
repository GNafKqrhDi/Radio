# Radio
The original intention of the internet was that every person was supposed to have their own page,
therefore without the need for a social medias to do it for the person. Perhaps some features such RSS feeds could be
used, but nothing more than that was necessary. The social network proposed intends to make the internet
closer to the way it was back then, but also improving on certain aspects that seem to have made people stop creating
their own websites. This means, people will host their network on their computer, but share the load with followers. It's called radio.

It’s called radio since every user will have his own ”station” to send files, by
using a randomly generated multicast channel. People who follow the user will actually be listening to his own multicast channel address.
If someone is not present during a period that someone he follows posts something, when entering the network, the algorithm will connect to peers to send back what happened in the network, therefore the user only share files sent by people he follow.
# Torrents

In order to decrease the volume of data in user's network, when he sends a file, he will actually be sending to his peers the link of the torrent of the file. Therefore users on the network only download files they want. For

# Message aunthentication

Every message is sent together with a key and hash. The key will be used to confirm that the message was sent by this particular user, since every user in the network store the hash of the key, and the hash sent will replace the hash that every user currently have. Passwords are generated by the algorithm, not the users.

# 51% attack
To handle 51% attack, the algorithm when receiving files from peers will decide based on the score of the peers (estimate of probability of sending the correct file), which file is more probable to be the correct one, doing a process similar to a proof of stake. The formula and the proof of it is contained in the "doc.pdf" file

# Sign up

To avoid users creating an infinity of users on the network, when connecting for the first time, the user will need to send a proof of work together to become a member of the network.

# Content moderation

A user has control only on his own network where he can block people from posting comments or participating on the network, and also of course people he follow.

# Running

```
chmod +x app.sh
./app.sh

```
