package autoTests;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class ApplicationTest {

   @Test
   public void testApplication_noDefenses() {
	   
	   System.out.println("########## TESTS FOR APPLICATION ##########");
	   
	   System.out.println("~~~~~ NO DEFENSES IN PLACE ~~~~~");
	   
	   AccessKey key = new AccessKey();
	   Instance instance = new Instance();
	   OperatingSystem operatingSystem = new OperatingSystem();
	   Account OSacct = new Account();
	   Application application = new Application();
	   Account appacct = new Account();
	   	   
	   key.addAssignedInstances(instance);		
	   key.addAssignedOSaccount(OSacct);
	   instance.addExecutees(operatingSystem);
	   operatingSystem.addAssignedAccounts(OSacct);
	   operatingSystem.addExecutees(application);
	   application.addAssignedAccounts(appacct);
		   
	   Attacker attacker = new Attacker();
	   attacker.addAttackPoint(instance.connect);
	   attacker.addAttackPoint(key.compromise);
	   attacker.addAttackPoint(appacct.compromise);
	   
	   attacker.attack();
	   
	   instance.keyaccess.assertCompromisedInstantaneously();
	   instance.attemptConnectBasicAWSProtection.assertCompromisedInstantaneously();
	   instance.authenticate.assertCompromisedInstantaneously();
	   instance.authenticatedAccess.assertCompromisedInstantaneously();
	   instance.access.assertCompromisedInstantaneously();
	   instance._machineAccess.assertCompromisedInstantaneously();
	   operatingSystem.connect.assertCompromisedInstantaneously();
	   operatingSystem.authenticate.assertCompromisedInstantaneously();
	   operatingSystem.authenticatedAccess.assertCompromisedInstantaneously();
	   operatingSystem.access.assertCompromisedInstantaneously();
	   operatingSystem._softwareAccess.assertCompromisedInstantaneously();
	   application.connect.assertCompromisedInstantaneously();
	   application.authenticate.assertCompromisedInstantaneously();
	   application.authenticatedAccess.assertCompromisedInstantaneously();
	   application.access.assertCompromisedInstantaneously();
	   application.attemptAccessNoFirewall.assertCompromisedInstantaneously();
	   application._machineAccess.assertCompromisedInstantaneously();
	  
   }
   
   @Test
   public void testApplication_allDefenses() {
	   
	   System.out.println("~~~~~ ALL DEFENSES IN PLACE ~~~~~");
	   
	   AccessKey key = new AccessKey();
	   Instance instance = new Instance();
	   OperatingSystem operatingSystem = new OperatingSystem();
	   Account OSacct = new Account();
	   Application application = new Application(true, true);
	   Account appacct = new Account();
	   	   
	   key.addAssignedInstances(instance);		
	   key.addAssignedOSaccount(OSacct);
	   instance.addExecutees(operatingSystem);
	   operatingSystem.addAssignedAccounts(OSacct);
	   operatingSystem.addExecutees(application);
	   application.addAssignedAccounts(appacct);
		   
	   Attacker attacker = new Attacker();
	   attacker.addAttackPoint(instance.connect);
	   attacker.addAttackPoint(key.compromise);
	   attacker.addAttackPoint(appacct.compromise);
	   
	   attacker.attack();
	   
	   instance.keyaccess.assertCompromisedInstantaneously();
	   instance.attemptConnectBasicAWSProtection.assertCompromisedInstantaneously();
	   instance.authenticate.assertCompromisedInstantaneously();
	   instance.authenticatedAccess.assertCompromisedInstantaneously();
	   instance.access.assertCompromisedInstantaneously();
	   instance._machineAccess.assertCompromisedInstantaneously();
	   operatingSystem.connect.assertCompromisedInstantaneously();
	   operatingSystem.authenticate.assertCompromisedInstantaneously();
	   operatingSystem.authenticatedAccess.assertCompromisedInstantaneously();
	   operatingSystem.access.assertCompromisedInstantaneously();
	   operatingSystem._softwareAccess.assertCompromisedInstantaneously();
	   application.connect.assertCompromisedInstantaneously();
	   application.authenticate.assertCompromisedInstantaneously();
	   application.authenticatedAccess.assertCompromisedInstantaneously();
	   application.access.assertCompromisedInstantaneously();
	   application.attemptAccessWithFirewall.assertCompromisedWithEffort();
	   application._machineAccess.assertCompromisedWithEffort();
	  
   }
   
	@After
	public void deleteModel() {
		Asset.allAssets.clear();
		AttackStep.allAttackSteps.clear();
		Defense.allDefenses.clear();
	}


}


