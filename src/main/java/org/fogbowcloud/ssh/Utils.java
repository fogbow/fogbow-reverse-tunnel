package org.fogbowcloud.ssh;

import java.math.BigDecimal;

public class Utils {
	
	public static boolean isNumber(String value){
		if(value != null){
			try{
				BigDecimal bd = new BigDecimal(value);
				bd = null;
				return true;
			}catch(NumberFormatException nfe){
				return false;
			}
		}
		return false;
	}

}
