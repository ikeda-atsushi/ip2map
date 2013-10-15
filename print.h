/***********************************************************************************************************************
 *
 * ip2map :  This program shows you the locations of the computers that are sending packets to your computer on a map.  
 * Copyright (C) 2013 Atsushi Ikeda: ikeda.atsushi@gmail.com							        
 * 														        
 * This program is free software; you can redistribute it and/or						        
 * modify it under the terms of the GNU General Public License							        
 * as published by the Free Software Foundation; either version 2						        
 * of the License, or (at your option) any later version.							        
 * 														        
 * This program is distributed in the hope that it will be useful,						        
 * but WITHOUT ANY WARRANTY; without even the implied warranty of						        
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the						        
 * GNU General Public License for more details.									        
 *														        
 * You should have received a copy of the GNU General Public License						        
 * along with this program; if not, write to the Free Software							        
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.				        
 *
 ************************************************************************************************************************/

#ifndef __PRINT__
#define __PRINT__

char *my_ether_ntoa_r(u_char *hwaddr, char *buf, socklen_t size);
char *arp_ip2str(u_int8_t *ip, char *buf, socklen_t size);
char *ip_ip2str(u_int32_t ip, char *buf, socklen_t size);
int PrintEtherHeader(struct ether_header *eth, FILE *fp);
int PrintArp(struct ether_arp *arp, FILE *fp);
int PrintIpHeader(struct iphdr *iphdr, u_char *option, int optionLen, FILE *fp);
int PrintIp6Header(struct ip6_hdr *ip6, FILE *fp);
int PrintIcmp(struct icmp *icmp, FILE *fp);
int PrintIcmp6(struct icmp6_hdr *icmp6, FILE *fp);
int PrintTcp(struct tcphdr *tcphdr, FILE *fp);
int PrintUdp(struct udphdr *udphdr, FILE *fp);

#endif
