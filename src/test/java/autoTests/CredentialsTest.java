package autoTests;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class CredentialsTest {

   @Test
   public void testCredentials() {
	   
	   System.out.println("########## TESTS FOR CREDENTIALS ##########");
	   
	   System.out.println("~~~~~ NO DEFENSES IN PLACE / ALL DEFENSES IN PLACE ~~~~~");
	   
	   Account account = new Account();
	   Credentials credentials = new Credentials();
	   AuthenticationService authServ = new AuthenticationService(); 
	   
	   authServ.addAuthenticatedAccounts(account);
	   account.addCredentials(credentials);
	   
	   Attacker attacker = new Attacker();
	   attacker.addAttackPoint(credentials.attemptCrack);
	   attacker.attack();
	   
	   account.authenticate.assertCompromisedInstantaneously();
	  
   }

	@After
	public void deleteModel() {
		Asset.allAssets.clear();
		AttackStep.allAttackSteps.clear();
		Defense.allDefenses.clear();
	}


}


