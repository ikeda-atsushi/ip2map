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

#ifndef __ANALYZE__
#define __ANALYZE__

int AnalyzeArp(u_char *data, int size);
int AnalyzeIcmp(u_char *data, int size);
int AnalyzeIcmp6(u_char *data, int size);
int AnalyzeTcp(u_char *data, int size);
int AnalyzeUdp(u_char *data, int size);
int AnalyzeIp(u_char *data, int size);
int AnalyzeIpv6(u_char *data, int size);
int AnalyzePacket(u_char *data, int size);

#endif
