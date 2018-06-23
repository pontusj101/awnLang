package autoTests;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class TestUseCaseVPCs_SecurityGroups {
	
	/*
	 * 
	 * 		  AuthenticationService
	 * 					|
	 * 			    Credentials
	 *					| 
	 * 		User -> IAMaccount ----------------
	 * 				 __________________________|________________________
	 * 				|									  				|
	 * 					NetworkService <-> Dataflow <-> NetworkClient
	 * 										  |
	 * 									 SecurityGroup
	 * 
	 * 		User has an IAM account that they use to control a VPC (two subnets connected to each other via a gateway).
	 * 		There's a network service that connects to a network client through a dataflow. Communication between the
	 * 		two are controlled by a security group.
	 * 
	 * 		(All defenses in place. Not shown in figure.)
	 * 		
	 * 		Attacker is able to compromise the user's IAM account.
	 * 
	 */

   @Test
   public void testvpcsecuritygroups() {
	   
	  System.out.println("########## USE CASE TESTS FOR SECURITY GROUPS ##########");
	  
	  User user = new User("user", true);														// user is security aware
	  IAMaccount iam = new IAMaccount("iam");
	  Credentials cred = new Credentials("namepass");
	  AuthenticationService authServ = new AuthenticationService("authServ", true, true);		// authentication service is firewall protected and patch up-to-date
	  NetworkService netServ = new NetworkService("netServ", true, true);						// network service is firewall protected and patch up-to-date
	  NetworkClient netClt = new NetworkClient("netClt", true, true);							// network client is firewall protected and patch up-to-date
	  Dataflow flow = new Dataflow("flow", true);
	  SecurityGroup secGrp = new SecurityGroup("secGrp");
	  
	  user.addAccounts(iam);
	  iam.addCredentials(cred);
	  iam.addSecurityGroup(secGrp);			 					// the IAM account created the security group
	  authServ.addAuthenticatedAccounts(iam);
	  netClt.addDataflows(flow);
	  netServ.addDataflows(flow);
	  flow.addSecurityGroup(secGrp);
	  
	  Attacker attacker = new Attacker();
      attacker.addAttackPoint(iam.compromise);
      attacker.attack();
      
      secGrp.compromisedAccess.assertCompromisedInstantaneously();
      flow.denialOfService.assertCompromisedInstantaneously();

      }
   
   @After
   public void deleteModel() {
           Asset.allAssets.clear();
           AttackStep.allAttackSteps.clear();
           Defense.allDefenses.clear();
   }
}
