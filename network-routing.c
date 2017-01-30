#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>

//global variables
int fake_ip[4];
int fake_wlan[6];
int port_number;
int sockid;

char neighbor_fake_ips[5][15];
struct sockaddr_in neighbor_addresses[5];
int neighbors;

int checksums_seen[6] = {0,0,0,0,0,0};
int checksums_seen_index = 0;

int packets_received = 0;

//network port numbers
int network[12] = {5061, 5058, 5060, 5059, 5057, 5056, 5053, 5052, 5051, 5040, 5055, 5054};

//initial distance to all other nodes - large numbers
int distance_vector[12] = {100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100};

//routing table arrays
char* routing_table_destinations[12] = {"7.0.0.161", "7.0.0.158", "7.0.0.160", "7.0.0.159",
                                        "7.0.0.157", "7.0.0.156", "7.0.0.153", "7.0.0.152",
                                        "7.0.0.151", "7.0.0.140", "7.0.0.155", "7.0.0.154"};
char routing_table_next_hops[12][15];

//functions
void parse_config(FILE *f_ptr);
void* receiver();
void* sender(void *args);  
char* parse_received_frame(unsigned char *frame, int frame_length);
void print_distance_vector();


//read config file, set global variables, create socket, spawn sender/receiver threads
int main(int argc, char *argv[]) {

    //assure correct # of arguments supplied
    if (argc != 3) {
    
        printf("Invalid number of arguments supplied\n");
        return 1;
    }

    //open config file
	FILE *f_ptr;
	f_ptr = fopen(argv[1], "r");

	if (!f_ptr) {

		printf("Error Opening File");
		return 1;
	}

    //parse config file and set global variables
    parse_config(f_ptr);

    //close config file
    fclose(f_ptr);

    //create socket
    sockid = socket(AF_INET, SOCK_DGRAM, 0);

    //check for socket creation error
    if (sockid < 0) {

        printf("Socket Creation Error");
	    return 0;
    }    

    //create sockaddr_in for socket binding
    struct sockaddr_in sockaddr;
    memset((char*) &sockaddr, 0, sizeof(sockaddr));
    sockaddr.sin_family = AF_INET;
    inet_aton("127.0.0.1", &sockaddr.sin_addr);
    sockaddr.sin_port = htons(port_number);

    //bind socket and check for binding error
    if (bind(sockid, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) < 0) {

	    printf("Socket Bind Error");
	    return 0;
    }

    //spawn receiver and sender threads
    pthread_t receiver_thread;
    pthread_t sender_thread;

    pthread_create(&receiver_thread, NULL, receiver, NULL);
    pthread_create(&sender_thread, NULL, sender, argv[2]);

    //wait for sender and receiver to finish
    pthread_join(receiver_thread, NULL);
    pthread_join(sender_thread, NULL);

    //close socket
    close(sockid);

	return 0;
}

//parse config file given as command line argument and set appropriate global variables
void parse_config(FILE *f_ptr) {

    //read lines from config file
    char line_buffer[128];

    //get fake ip address line
    fgets(line_buffer, 128, f_ptr);

    char *delimited_chars;
    int delimited_count = 0;

    //split fake ip address by "." and store contents in array
    delimited_chars = strtok(line_buffer, ".");
    fake_ip[delimited_count] = atoi(delimited_chars);
    delimited_count += 1;

    //continue splitting until end of string
    while (delimited_chars != NULL) {

        delimited_chars = strtok(NULL, ".");

        if (delimited_count < 4)        
            fake_ip[delimited_count] = atoi(delimited_chars);
        
        delimited_count += 1;
    }

    /*//TODO
    //get fake wlan address line
    fgets(line_buffer, 128, f_ptr);

    delimited_count = 0;

    //split fake wlan address by ":" and store contents in array
    delimited_chars = strtok(line_buffer, ":");
    fake_wlan[delimited_count] = atoi(delimited_chars);
    delimited_count += 1;

    //continue splitting until end of string
    while (delimited_chars != NULL) {

        delimited_chars = strtok(NULL, ":");

        if (delimited_count < 6)  
            fake_wlan[delimited_count] = strtol(delimited_chars, NULL, 16);
        
        delimited_count += 1;
    }*/
  
    //get port number line and store as int
    fgets(line_buffer, 128, f_ptr);
    port_number = atoi(line_buffer);

    //initial distance to self - 0
    distance_vector[node_index(port_number)] = 0;

    //get number of neighbors line and store as int
    fgets(line_buffer, 128, f_ptr);
    int num_neighbors = atoi(line_buffer);

    neighbors = num_neighbors;

    //create socket addresses for all neighbors
    int i;
    for (i = 0; i < num_neighbors; i++) {

        int neighbor_port;

        //get next neighbor info
        fgets(line_buffer, 128, f_ptr);
        delimited_count = 0;

        //split neighbor info by spaces and extract important info
        delimited_chars = strtok(line_buffer, " ");
        
        delimited_count += 1;

        //extract fake ip info for current neighbor
        char* neighbor_fake_ip = delimited_chars;
        strcpy(neighbor_fake_ips[i], neighbor_fake_ip);  

        //continue splitting until end of string
        while (delimited_chars != NULL) {

            delimited_chars = strtok(NULL, " ");

            //extract port number from 3rd element of neighbor info
            if (delimited_count == 2)  
                neighbor_port = atoi(delimited_chars);
            
            delimited_count += 1;
        }

        //initial distance to neighbors - 1 
        int neighbor_index = node_index(neighbor_port);
        distance_vector[neighbor_index] = 1;

        //next hop to neighbors - neighbors
        strcpy(routing_table_next_hops[neighbor_index], neighbor_fake_ip);
    
        //set appropriate info for neighbor socket addresses
        memset((char*) &neighbor_addresses[i], 0, sizeof(neighbor_addresses[i]));
        neighbor_addresses[i].sin_family = AF_INET;
        inet_aton("127.0.0.1", &neighbor_addresses[i].sin_addr);
        neighbor_addresses[i].sin_port = htons(neighbor_port);
    }

    /*//TODO
    //get number of frames line
    fgets(line_buffer, 128, f_ptr);

    //get routing table size line (subtract 1 to exclude this node in table)
    fgets(line_buffer, 128, f_ptr);
    int routing_table_size = atoi(line_buffer) - 1;

    for (i = 0; i < routing_table_size; i++) {

        //get routing info line
        fgets(line_buffer, 128, f_ptr);

        //split routing info by " " and store contents in appropriate arrays
        delimited_chars = strtok(line_buffer, " ");
        strcpy(routing_table_destinations[i], delimited_chars);        
        delimited_chars = strtok(NULL, " ");
        strcpy(routing_table_next_hops[i], delimited_chars);
        routing_table_next_hops[i][strcspn(routing_table_next_hops[i], "\n")] = 0;
    }*/
}

//receive and parse frames sent from other hosts - print frame contents if this host is the intended destination
void* receiver() {

    //loop counters
    int i, j;

    //buffer to hold received information
    int receiving_buffer_length = 256;
    unsigned char receiving_buffer[receiving_buffer_length];

    //socket address variables to capture sender information
    struct sockaddr_in sender_addr;
    socklen_t sender_addr_length = sizeof(sender_addr);

    //length of received message
    int message_length;

    char* received_intended;

    //receive all incoming messages until program is manually terminated
    while (1) {
    
        //receive message, put it in receiving_buffer, and put its length in message_length
        message_length = recvfrom(sockid, receiving_buffer, receiving_buffer_length, 
                                  0, (struct sockaddr*) &sender_addr, &sender_addr_length);

        //message received case
        if (message_length > 0) {               

            //distance vector case
            if (message_length == 12) {

                //get port of sender
                int sender_port = ntohs(sender_addr.sin_port);

                //check to see if any new distances are shorter
                for (i = 0; i < 12; i++) {

                    //distance from neighbor to destination + distance from this node to neighbor
                    //compared to current distance
                    if (receiving_buffer[i] + 1 < distance_vector[i]) {

                        //new distance
                        distance_vector[i] = receiving_buffer[i] + 1;
            
                        //new next hop - routing table sender
                        strcpy(routing_table_next_hops[i], routing_table_destinations[node_index(sender_port)]); 
                    }
                }
            }

            //frame case
            else {

                //give frame to frame parser 
                received_intended = parse_received_frame(receiving_buffer, message_length); 

                //print number of frames received
                packets_received += 1;
                printf("Packets Received: %d\n\n", packets_received);

                //routing case
                if (strcmp(received_intended, "confirmation") != 0) {

                    for (i = 0; i < 11; i++) {

                        if (strcmp(received_intended, routing_table_destinations[i]) == 0) {
                
                            for (j = 0; j < neighbors; j++) {

                                if (strncmp(routing_table_next_hops[i], neighbor_fake_ips[j], strlen(neighbor_fake_ips[j])) == 0) { 

                                    sendto(sockid, receiving_buffer, sizeof(receiving_buffer), 0, 
                                          (struct sockaddr*) &neighbor_addresses[j], sizeof(neighbor_addresses[j]));
                                }
                            }                
                        }
                    }
                }
            }
        }
    }
}

//parse a single WLAN frame and output relevant information about it if it was meant for this host
char* parse_received_frame(unsigned char *frame, int frame_length) {

    //loop counters
    int i, j;

    //current frame read location
    int frame_byte_counter = 0;

    //ignore PLCP Preamble/Header
    frame_byte_counter += 24;

    //2 bytes-Frame Control
    unsigned char frame_control[2];
    for (i = 0; i < sizeof(frame_control); i++) {

        frame_control[i] = frame[frame_byte_counter];
        frame_byte_counter += 1;
    }

    //Extract bits from frame control bytes
    unsigned char frame_control_bits[16];
    for (i = 0; i < sizeof(frame_control); i++) {    

        for (j = 0; j < 8; j++) {

            //place extracted bit in an appropriate bit array index
            frame_control_bits[(i*8)+7-j] = (frame_control[i] & (1 << j)) != 0;
        }
    }

    //Use extracted bits to determine to/from Ds
    int to_Ds = frame_control_bits[15];
    int from_Ds = frame_control_bits[14];

    //Use to/from Ds to set appropriate state variable
    int ds = 0;
    if (to_Ds == 0 && from_Ds == 1) {

        ds = 1;
    }
    else if (to_Ds == 1 && from_Ds == 0) {

        ds = 2;
    }
    else if (to_Ds == 1 && from_Ds == 1) {
    
        ds = 3;
    }

    //Use to/from Ds to determine if the 'ADDR 4' field will be present in the frame
    int address4_used = 0;
    if (ds == 3) {

        address4_used = 1;
    }
    
    //2 bytes-Duration ID
    unsigned char duration_id[2];
    for (i = 0; i < sizeof(duration_id); i++) {

        duration_id[i] = frame[frame_byte_counter];
        frame_byte_counter += 1;
    }

    //6 bytes-Addr 1
    unsigned char addr_1[6];
    for (i = 0; i < sizeof(addr_1); i++) {

        addr_1[i] = frame[frame_byte_counter];
        frame_byte_counter += 1;
    }

    //6 bytes-Addr 2
    unsigned char addr_2[6];
    for (i = 0; i < sizeof(addr_2); i++) {

        addr_2[i] = frame[frame_byte_counter];
        frame_byte_counter += 1;
    }

    //6 bytes-Addr 3
    unsigned char addr_3[6];
    for (i = 0; i < sizeof(addr_3); i++) {

        addr_3[i] = frame[frame_byte_counter];
        frame_byte_counter += 1;
    }

    //2 bytes-Sequence Control
    unsigned char sequence_control[2];
    for (i = 0; i < sizeof(sequence_control); i++) {

        sequence_control[i] = frame[frame_byte_counter];
        frame_byte_counter += 1;
    }

    //6 bytes-Addr 4 
    unsigned char addr_4[6];
    if (address4_used) {

        for (i = 0; i < sizeof(addr_4); i++) {

            addr_4[i] = frame[frame_byte_counter];
            frame_byte_counter += 1;
        }
    }

    //Use previously determined state (from to/from Ds bits) to set appropriate address values
    unsigned char *frame_da;
    unsigned char *frame_sa;
    if (ds == 0) {
    
        frame_da = addr_1;
        frame_sa == addr_2;
    }
    else if (ds == 1) {

        frame_da = addr_1;
        frame_sa = addr_3;
    }
    else if (ds == 2) {

        frame_da = addr_3;
        frame_sa = addr_2;
    }
    else {
    
        frame_da = addr_3;
        frame_da = addr_4;
    }

    //3 bytes-LLC
    unsigned char llc[3];
    for (i = 0; i < sizeof(llc); i++) {

        llc[i] = frame[frame_byte_counter];
        frame_byte_counter += 1;
    }

    //3 bytes-Org Code
    unsigned char org_code[3];
    for (i = 0; i < sizeof(org_code); i++) {

        org_code[i] = frame[frame_byte_counter];
        frame_byte_counter += 1;
    }

    //2 bytes-Type
    unsigned char type[2];
    for (i = 0; i < sizeof(type); i++) {

        type[i] = frame[frame_byte_counter];
        frame_byte_counter += 1;
    }

    //Use type bytes to create a descriptive string for the type field
    char type_description[7];
    strcpy(type_description, "Unknown");
    
    if (type[0] == 8 && type[1] == 0) {
        
        strcpy(type_description, "IP");
    }

    //determine index of time_to_live so it can be decremented later
    int time_to_live_index = frame_byte_counter + 8;

    //20 bytes-IP Header
    unsigned char ip_header[20];
    for (i = 0; i < sizeof(ip_header); i++) {

        ip_header[i] = frame[frame_byte_counter];
        frame_byte_counter += 1;
    }
    
    //Extract bits from IP header bytes
    unsigned char ip_header_bits[160];
    for (i = 0; i < sizeof(ip_header); i++) {    

        for (j = 0; j < 8; j++) {

            //place extracted bit in an appropriate bit array index
            ip_header_bits[(i*8)+7-j] = (ip_header[i] & (1 << j)) != 0;
        }
    }

    //Current IP header byte
    int header_index = 0;

    //4 bits-Version
    unsigned char version[4];
    for (i = 0; i < sizeof(version); i++) {
    
        version[i] = ip_header_bits[header_index];
        header_index++;
    }
    
    //4 bits-IHL
    unsigned char ihl[4];
    for (i = 0; i < sizeof(ihl); i++) {
    
        ihl[i] = ip_header_bits[header_index];
        header_index++;
    }

    //Extract ip header length in decimal form
    int header_length = bits_to_decimal(ihl, sizeof(ihl));
    header_length *= 4; //conver from # of 32 bit words to # of bytes
    
    //8 bits-Type of Service
    unsigned char type_of_service[8];
    for (i = 0; i < sizeof(type_of_service); i++) {
    
        type_of_service[i] = ip_header_bits[header_index];
        header_index++;
    }

    //16 bits-Total Length
    unsigned char tl[16];
    for (i = 0; i < sizeof(tl); i++) {
    
        tl[i] = ip_header_bits[header_index];
        header_index++;
    }
    
    //Extract total ip packet length in decimal form
    int total_length = bits_to_decimal(tl, sizeof(tl));

    //16 bits-Identification
    unsigned char identification[16];
    for (i = 0; i < sizeof(identification); i++) {
    
        identification[i] = ip_header_bits[header_index];
        header_index++;
    }

    //3 bits-Flags
    unsigned char flags[3];
    for (i = 0; i < sizeof(flags); i++) {
    
        flags[i] = ip_header_bits[header_index];
        header_index++;
    }

    //13 bits-Fragment Offset
    unsigned char fragment_offset[13];
    for (i = 0; i < sizeof(fragment_offset); i++) {
    
        fragment_offset[i] = ip_header_bits[header_index];
        header_index++;
    }

    //8 bits-Time to Live
    unsigned char time_to_live[8];

    for (i = 0; i < sizeof(time_to_live); i++) {
    
        time_to_live[i] = ip_header_bits[header_index];
        header_index++;
    }

    //8 bits-Protocol
    unsigned char protocol[8];
    for (i = 0; i < sizeof(protocol); i++) {
    
        protocol[i] = ip_header_bits[header_index];
        header_index++;
    }

    //(header bytes - 20) bytes-Options 
    int option_bytes = header_length - 20;
    unsigned char options[option_bytes];
    for (i = 0; i < sizeof(options); i++) {

        options[i] = frame[frame_byte_counter];
        frame_byte_counter += 1;
    }

    //(total bytes - header bytes) bytes-Payload
    int payload_bytes = total_length - header_length;
    unsigned char payload[payload_bytes];
    for (i = 0; i < sizeof(payload); i++) {

        payload[i] = frame[frame_byte_counter];
        frame_byte_counter += 1;
    }

    //4 bytes-Frame Check Sequence
    unsigned char frame_check_sequence[4];
    for (i = 0; i < sizeof(frame_check_sequence); i++) {

        frame_check_sequence[i] = frame[frame_byte_counter];
        frame_byte_counter += 1;
    }  

    //print source, destination
    printf("Source IP      : %d.%d.%d.%d\n", ip_header[12], ip_header[13], ip_header[14], ip_header[15]);
    printf("Destination IP : %d.%d.%d.%d\n", ip_header[16], ip_header[17], ip_header[18], ip_header[19]);

    //if the frame is intended for this host, print it and return confirmation
    if (fake_ip[0] == ip_header[16] && fake_ip[1] == ip_header[17] && 
        fake_ip[2] == ip_header[18] && fake_ip[3] == ip_header[19]) {

        int frame_seen = 0;

        //compute checksum value
        int checksum = (int) (ip_header[10]*256 + ip_header[11]);

        //print received confirmation + checksum
        printf("Frame Received - Checksum : %X\n", checksum);

        /* //TODO

        //check if this checksum value has been seen (i.e. for this project - this frame has been received)
        for (i = 0; i < 6; i++) {

            if (checksum == checksums_seen[i]) {

                frame_seen = 1;           
            }
        }

        //TODO set to 0 when not testing
        int testing = 1;

        if (!frame_seen || !testing) {

            checksums_seen[checksums_seen_index] = checksum;
            checksums_seen_index += 1;    

            //WLAN frame output
            printf("WLAN:    ----- WLAN HEADER -----\n");
            printf("WLAN:    \n");
            printf("WLANL    Packet size : %d bytes\n", total_length + 36 + address4_used*6);
            printf("WLAN:    Destination : %02X-%02X-%02X-%02X-%02X-%02X\n", frame_da[0], frame_da[1], frame_da[2], 
                                                                             frame_da[3], frame_da[4], frame_da[5]);
            printf("WLAN:    Source      : %02X-%02X-%02X-%02X-%02X-%02X\n", frame_sa[0], frame_sa[1], frame_sa[2], 
                                                                             frame_sa[3], frame_sa[4], frame_sa[5]);
            printf("WLAN:    Type        : %02X%02X (%s)\n", type[0], type[1], type_description);
            printf("IP:      ----- IP HEADER -----\n");
            printf("IP:      \n"); 
            printf("IP:      Version = %d\n", bits_to_decimal(version, sizeof(version)));
            printf("IP:      Header length = %d bytes\n", header_length);
            printf("IP:      Type of service = 0x%02X\n", ip_header[1]);
            printf("IP:      Total length = %d bytes\n", total_length);
            printf("IP:      Identification =  %d\n", bits_to_decimal(identification, sizeof(identification)));
            printf("IP:      Flags = 0x%d\n", bits_to_decimal(flags, sizeof(flags)));
            printf("IP:      Fragment offset = %d bytes\n", bits_to_decimal(fragment_offset, sizeof(fragment_offset)));
            printf("IP:      Time to live = %d seconds/hops\n", bits_to_decimal(time_to_live, sizeof(time_to_live)));
            printf("IP:      Protocol = %d\n", bits_to_decimal(protocol, sizeof(protocol)));
            printf("IP:      Header checksum = 0x%X%X\n", ip_header[10], ip_header[11]);
            printf("IP:      Source address = %d.%d.%d.%d\n", ip_header[12], ip_header[13], ip_header[14], ip_header[15]);
            printf("IP:      Destination address = %d.%d.%d.%d\n", ip_header[16], ip_header[17], ip_header[18], ip_header[19]);
            printf("IP:      ");
            
            //output options field
            if (option_bytes > 0) {

                for (i = 0; i < sizeof(options); i++) {
               
                    printf("%X", options[i]);
                }
            }
            else {

                printf("No options");
            }
            printf("\n\n");

            //output each frame byte
            for (i = 24; i < frame_length; i++) {

                //output row headers
                if ((i - 24) % 16 == 0) {

                    printf("%03d0 ", (i - 24) / 16);
                }

                //output frame bytes
                printf("%02X ", frame[i]);

                //16 bytes per line
                if (((i - 24)+1) % 16 == 0 || i == frame_length - 1) {

                    //fill final incomplete row with 00's
                    if (i == frame_length - 1) {

                        for (j = 0; j < 16 - (((i - 24)+1) % 16); j++) {
            
                            printf("00 ");
                        }
                    }

                    //output ascii version of first 8 bytes of row if possible, else print '.'
                    for (j = i-15; j < i-7; j++) {

                        if (frame[j] >= 33 && frame[j] <= 126) {

                            printf("%c", frame[j]);
                        }
                        else {

                            printf(".");
                        }
                    }

                    //output formatting
                    printf(" ");
                    
                    //output ascii version of last 8 bytes of row if possible, else print '.'
                    for (j = i-7; j < i + 1; j++) {

                        if (frame[j] >= 33 && frame[j] <= 126) {

                            printf("%c", frame[j]);
                        }
                        else {

                            printf(".");
                        }
                    }
                    printf("\n");
                }
            }

            //output formatting
            printf("\n\n\n");
        }

        */ //TODO

        printf("\n");

        return "confirmation";
    }

    //if time to live is not 0, decrement it
    //if (frame[time_to_live_index] > 0) {

    //    frame[time_to_live_index] = frame[time_to_live_index] - 1; 

    //}

    printf("\n");

    //create char array to return
    char *buffer = malloc(15 * sizeof(char));
    snprintf(buffer, 15, "%d.%d.%d.%d", ip_header[16], ip_header[17], ip_header[18], ip_header[19]);

    //return intended destination for this message
    return buffer;
}

//parse input file and send appropriate frames to all neighbors
void* sender(void *args) {

    //sleep to give receiver threads time to set up
    sleep(5);

    //loop counter
    int i;

    //distance vector round counter
    int distance_vector_count = 0;

    //send distance vectors to neighbors
    while (1) {

        //copy of distance vector
        unsigned char buffer[12];
        for (i = 0; i < 12; i++) { buffer[i] = distance_vector[i]; }

        //send distance vector to neighbors
        for (i = 0; i < neighbors; i++)                            
            sendto(sockid, buffer, sizeof(buffer), 0, (struct sockaddr*) &neighbor_addresses[i], sizeof(neighbor_addresses[i]));  

        //increment distance vector counter
        distance_vector_count++;

        //sleep for 3 seconds to give this round of distance vector time to complete
        sleep(5);

        //print routing table % currect distances every round (+1 to account for initial round of neighbor info)
        printf("Routing Table after %d rounds of distance vector\n", distance_vector_count + 1);
        for (i = 0; i < 12; i++) {

            printf("%s : %s : %d\n", routing_table_destinations[i], routing_table_next_hops[i], distance_vector[i]);    
        }
        printf("\n");

        //stop distance vector condition (9 rounds is sufficient because it is the diameter of the network)
        if (distance_vector_count == 8) { break; }
    }

    //sleep for 5 seconds to give last node time to finish last distance vector round before frames are sent
    sleep(5);

    //input file given as command line argument and passed here from main
    char *input = (char*) args;

    //open input file
    FILE *f_ptr;
    f_ptr = fopen(input, "rb");

	if (!f_ptr) {

		printf("Error Opening File");
		return;
	}
    
    //parse input and send appropriate frames
    int eof = 0;
    while (eof == 0) {
    
        //check/send? next frame        
        eof = check_send_frame(f_ptr);

        //ignore inter-frame spacing
        fseek(f_ptr, 12, SEEK_CUR);
    }

	fclose(f_ptr); //close file
	return;
}

//parse a single WLAN frame and output relevant information about it
int check_send_frame(FILE *f_ptr) {

    //loop counters
    int i, j;

    //ignore PLCP Preamble/Header
    fseek(f_ptr, 24, SEEK_CUR); 

    //2 bytes-Frame Control
    unsigned char frame_control[2];
    if (fread(&frame_control, sizeof(frame_control), 1, f_ptr) != 1) { 
    
        return 1; 
    }

    //Extract bits from frame control bytes
    unsigned char frame_control_bits[16];
    for (i = 0; i < sizeof(frame_control); i++) {    

        for (j = 0; j < 8; j++) {

            //place extracted bit in an appropriate bit array index
            frame_control_bits[(i*8)+7-j] = (frame_control[i] & (1 << j)) != 0;
        }
    }

    //Use extracted bits to determin to/from Ds
    int to_Ds = frame_control_bits[15];
    int from_Ds = frame_control_bits[14];

    //Use to/from Ds to set appropriate state variable
    int ds = 0;
    if (to_Ds == 0 && from_Ds == 1) {

        ds = 1;
    }
    else if (to_Ds == 1 && from_Ds == 0) {

        ds = 2;
    }
    else if (to_Ds == 1 && from_Ds == 1) {
    
        ds = 3;
    }

    //Use to/from Ds to determine if the 'ADDR 4' field will be present in the frame
    int address4_used = 0;
    if (ds == 3) {

        address4_used = 1;
    }
    
    //ignore Duration ID
    fseek(f_ptr, 2, SEEK_CUR);

    //6 bytes-Addr 1
    unsigned char addr_1[6];
    if (fread(&addr_1, sizeof(addr_1), 1, f_ptr) != 1) {
    
        return 1; 
    }

    //6 bytes-Addr 2
    unsigned char addr_2[6];
    if (fread(&addr_2, sizeof(addr_2), 1, f_ptr) != 1) {
    
        return 1; 
    }

    //6 bytes-Addr 3
    unsigned char addr_3[6];
    if (fread(&addr_3, sizeof(addr_3), 1, f_ptr) != 1) {
    
        return 1; 
    }

    //ignore Sequence Control
    fseek(f_ptr, 2, SEEK_CUR);

    //6 bytes-Addr 4 
    unsigned char addr_4[6];
    if (address4_used) {

        if (fread(&addr_4, sizeof(addr_4), 1, f_ptr) != 1) {
        
            return 1; 
        }
    }

    //Use previously determined state (from to/from Ds bits) to set appropriate address values
    unsigned char *frame_da;
    unsigned char *frame_sa;
    if (ds == 0) {
    
        frame_da = addr_1;
        frame_sa == addr_2;
    }
    else if (ds == 1) {

        frame_da = addr_1;
        frame_sa = addr_3;
    }
    else if (ds == 2) {

        frame_da = addr_3;
        frame_sa = addr_2;
    }
    else {
    
        frame_da = addr_3;
        frame_da = addr_4;
    }

    //ignore LLC, Org Code, Type
    fseek(f_ptr, 8, SEEK_CUR);

    //20 bytes-IP Header
    unsigned char ip_header[20];
    if (fread(&ip_header, sizeof(ip_header), 1, f_ptr) != 1) {
    
        return 1; 
    }
    
    //Extract bits from IP header bytes
    unsigned char ip_header_bits[160];
    for (i = 0; i < sizeof(ip_header); i++) {    

        for (j = 0; j < 8; j++) {

            //place extracted bit in an appropriate bit array index
            ip_header_bits[(i*8)+7-j] = (ip_header[i] & (1 << j)) != 0;
        }
    }

    //Current IP header byte
    int header_index = 0;

    //ignore version
    header_index += 4;
    
    //4 bits-IHL
    unsigned char ihl[4];
    for (i = 0; i < sizeof(ihl); i++) {
    
        ihl[i] = ip_header_bits[header_index];
        header_index++;
    }

    //Extract ip header length in decimal form
    int header_length = bits_to_decimal(ihl, sizeof(ihl));
    header_length *= 4; //convert from # of 32 bit words to # of bytes
    
    //ignore Type of Service
    header_index += 8;

    //16 bits-Total Length
    unsigned char tl[16];
    for (i = 0; i < sizeof(tl); i++) {
    
        tl[i] = ip_header_bits[header_index];
        header_index++;
    }
    
    //Extract total ip packet length in decimal form
    int total_length = bits_to_decimal(tl, sizeof(tl));

    //ignore Identification, Flags, Fragment Offset, Time to Live, and Protocol

    //ignore Options, Payload, Frame Check Sequence
    int option_bytes = header_length - 20;
    int payload_bytes = total_length - header_length;
    fseek(f_ptr, option_bytes + payload_bytes + 4, SEEK_CUR);

    //reset pointer to beginning of frame
    int frame_bytes = total_length + 36 + (address4_used * 6) + 24;
    int seek_val = 0 - frame_bytes;
    fseek(f_ptr, seek_val, SEEK_CUR);

    //(frame_bytes) bytes-Entire Frame
    unsigned char frame[frame_bytes];
    if (fread(&frame, sizeof(frame), 1, f_ptr) != 1) {
    
        return 1; 
    }

    //check if the source address of this frame is the same as this host's address
    if (fake_ip[0] == ip_header[12] && fake_ip[1] == ip_header[13] && 
        fake_ip[2] == ip_header[14] && fake_ip[3] == ip_header[15]) {

        char buffer[15];
        snprintf(buffer, 15, "%d.%d.%d.%d", ip_header[16], ip_header[17], ip_header[18], ip_header[19]);

        //routing
        for (i = 0; i < 11; i++) {

            if (strcmp(buffer, routing_table_destinations[i]) == 0) {
    
                for (j = 0; j < neighbors; j++) {

                    if (strncmp(routing_table_next_hops[i], neighbor_fake_ips[j], strlen(neighbor_fake_ips[j])) == 0) { 

                        sendto(sockid, frame, sizeof(frame), 0, (struct sockaddr*) &neighbor_addresses[j], sizeof(neighbor_addresses[j]));
                    }
                }                
            }
        }
    }

    return 0;
}

//convert array of bits (unsigned chars) to a decimal int value
int bits_to_decimal(unsigned char bits[], size_t size) {

    //int to return
    int return_val = 0;
    int i;

    //sum digit values to compute decimal int
    for (i = 0; i < size; i++) {

        return_val += bits[i]*(int)pow((double)2, size-i-1);
    }

    return return_val;
}

//determine the routing table index based on port number
int node_index(int pn)
{
    int index = 0;

    while (index < 12 && network[index] != pn) { index += 1; }

    return index;
}

//print currect distances to all other network nodes
void print_distance_vector() {

    int n;
    for (n = 0; n < 12; n++) { printf("%d ", distance_vector[n]); }

    printf("\n");
}
