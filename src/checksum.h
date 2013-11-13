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

#ifndef __CHECKSUM__
#define __CHECKSUM__

u_int16_t checksum(u_char *data, int len);
u_int16_t checksum2(u_char *data1, int len1, u_char *data2, int len2);
int checkIPchecksum(struct iphdr *iphdr, u_char *option, int optionLen);
int checkIPDATAchecksum(struct iphdr *iphdr, unsigned char *data, int len);
int checkIP6DATAchecksum(struct ip6_hdr *ip, unsigned char *data, int len);

#endif
