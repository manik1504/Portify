import java.util.*;
import java.net.*;
import java.util.HashMap; 
import java.util.Map; 

public class portify
{
    public static void main(String args[])
    {
        System.out.println("\nWELCOME TO PORT BASED VULNERABILITY SCANNER");
        int start=0,end=0;
        Scanner sc= new Scanner(System.in);
       
        System.out.println("\n\nEnter the starting Port Address:");                     //Taking port range
        start = sc.nextInt();
        
        System.out.println("Enter the ending Port Address:");
        end = sc.nextInt();
        
        System.out.println("Enter the target ip address as w.x.y.z :");            //Taking target
       
        String ip;
        ip = sc.next();

        /*InetAddress address = InetAddress.getByName("www.google.com"); 

        System.out.println(address.getHostAddress());*/

        HashMap<Integer, String> port = new HashMap<> ();                          //Hashmap for storing port number and its status
        
        //System.out.println("Debug == "+(end-start));
        
        System.out.println("\nStarting Port Scan on host: "+ ip ); 
        
        for(int i=start,j=0;i<=end;i++,j++)                                                 //Loop for all ports in the range
        {
            try {
                Socket soc = new Socket(ip,i);                                      //establishing socket connection to check if port is open
               
                System.out.print("\b\b\b----"+((100/(end-start))*j)+"%");      //for loader
               
                // System.out.println(i+" Open");
              
                port.put(i,"Open");                                                 //adding port status in map
                soc.close();

            } catch (Exception e) {
                
                System.out.print("");
                port.put(i,"Closed");
            }
            System.out.print("\b\b\b----"+((100/(end-start)*j))+"%");          //for loader
            //System.out.println(i+" Closed");
        }
        

        System.out.println("\n\nCurrent Port Status for target "+ip+" is\n");
        System.out.println(port);                                                   //printing port status for all ports

        System.out.println("\nVulnerability Status: ");
        if(port.get(21)=="Open")
        {
            System.out.println("\nPort 21:\nService Name: FTP\nVulerabilities: Broken Access Control, Sensitive Data Exposure");
        }
        if(port.get(22)=="Open")
        {
            System.out.println("\nPort 22:\nService Name: SSH\nVulerabilities: Sensitive Data Exposure");
        }
        if(port.get(23)=="Open")
        {
            System.out.println("\nPort 23:\nService Name: Telnet\nVulerabilities: Broken Authentication, Sensitive Data Exposure");
        }
        if(port.get(25)=="Open")
        {
            System.out.println("\nPort 25:\nService Name: SMTP\nVulerabilities: Broken Access Control");
        }
        if(port.get(53)=="Open")
        {
            System.out.println("\nPort 53:\nService Name: DNS\nVulerabilities: Broken Authentication");
        }
        if(port.get(80)=="Open")
        {
            System.out.println("\nPort 80:\nService Name: HTTP\nVulerabilities: Sensitive Data Exposure, Broken Access Control, Injection, XSS");
        }
        if(port.get(110)=="Open")
        {
            System.out.println("\nPort 110:\nService Name: POP3\nVulerabilities: Security Misconfigurations, Sensitive Data Exposure");
        }
        if(port.get(135)=="Open")
        {
            System.out.println("\nPort 135:\nService Name: RPC\nVulerabilities: Sensitive Data Exposure");
        }
        if(port.get(137)=="Open")
        {
            System.out.println("\nPort 137:\nService Name: NetBIOS\nVulerabilities: Broken Access Control, Sensitive Data Exposure");
        }
        if(port.get(443)=="Open")
        {
            System.out.println("\nPort 443:\nService Name: HTTPS\nVulerabilities: Broken Access control");
        }
        if(port.get(1433)=="Open")
        {
            System.out.println("\nPort 1433:\nService Name: SQL\nVulerabilities: Injection, XSS");
        }


        if(port.get(21)!="Open"&&port.get(22)!="Open"&&port.get(23)!="Open"&&port.get(25)!="Open"&&port.get(53)!="Open"&&port.get(80)!="Open"&&port.get(110)!="Open"&&port.get(135)!="Open"&&port.get(443)!="Open"&&port.get(1433)!="Open"&&port.get(137)!="Open")
        {
            System.out.println("\nNo Vulnerabilities found on host "+ip);
        }
        else
        {
            String choice;
            
            System.out.println("Do you want to display the mitigation guidelines for Common Vulnerabilities (Y/N)?");
            choice = sc.next();

            if(choice.equals("Y")||choice.equals("y"))
            {
                System.out.println("\n1.Injection\n-> Use a safe API\n-> Use Server Side Input Validation\n-> Escape Special Characters");
                System.out.println("\n2.Broken Authentication\n-> Implement MFA\n-> Don't use default credentials\n-> Implement password checks\n-> Enable API Hardening\n-> Use Session Management\n-> Limit failed login attempts");
                System.out.println("\n3.Sensitive Data Exposure\n-> Use Data Classification\n-> Encrypt Sensitive Data\n-> Disable Caching\n-> Use Hashing");
                System.out.println("\n4.XML External Entities\n-> Use less complex data formats\n-> Use SOAP 1.2 or higher\n-> Disbale XEE processing\n-> Use server side Input Validation");
                System.out.println("\n5.Broken Access Control\n-> Deny by Default\n-> Disable Web Server Directory Listing\n-> Rate limit API");
                System.out.println("\n6.Cross Site Scripting (XSS)\n-> Escape untrusted HTTP request\n-> Use Context Sensitive Encoding");
                System.out.println("\n7.Insecure Deserialization\n-> Implement Integrity Checks\n-> Enforce Strict Type Constraints");
            }
            else
            {
                System.out.println("\nThank You for using our tool :)");
            }

       
        }
        System.out.println("\n");
    }
}