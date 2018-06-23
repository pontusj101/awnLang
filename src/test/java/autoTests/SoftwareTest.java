package autoTests;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class SoftwareTest {

   @Test
   public void testSoftware() {
	   
	   System.out.println("########## TESTS FOR SOFTWARE ##########");
	   
	   System.out.println("~~~~~ NO DEFENSES IN PLACE / ALL DEFENSES IN PLACE ~~~~~");		
	   												//	'Software' asset does have a defense called 'patchStatus', that relates to 'Vulnerability', which is unexplored as of yet
	   
	   Machine machine = new Machine();
	   Software software = new Software();
	   
	   machine.addExecutees(software);
	   
	   Attacker attacker = new Attacker();
	   attacker.addAttackPoint(software.connect);
	   attacker.addAttackPoint(software.authenticate);
	   attacker.attack();
	   
	   software.authenticatedAccess.assertCompromisedInstantaneously();
	   software.access.assertCompromisedInstantaneously();
	   software._softwareAccess.assertCompromisedInstantaneously();
	   machine.connect.assertCompromisedInstantaneously();
	  
   }
   
	@After
	public void deleteModel() {
		Asset.allAssets.clear();
		AttackStep.allAttackSteps.clear();
		Defense.allDefenses.clear();
	}


}


