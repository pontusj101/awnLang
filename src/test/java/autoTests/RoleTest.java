package autoTests;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class RoleTest {

   @Test
   public void testRole() {
	   
	   System.out.println("########## TESTS FOR ROLE ##########");
	   
	   System.out.println("~~~~~ NO DEFENSES IN PLACE / ALL DEFENSES IN PLACE ~~~~~");
	   
	   IAMaccount iamacct = new IAMaccount();
	   Role role = new Role();
	   
	   iamacct.addRole(role);
	   
	   Attacker attacker = new Attacker();
	   attacker.addAttackPoint(iamacct.compromise);
	   attacker.attack();
	   
	   iamacct.compromisedAccess.assertCompromisedInstantaneously();   
	   role.compromisedAccess.assertCompromisedInstantaneously();
	   role.addRole.assertCompromisedInstantaneously();
	   role.deleteRole.assertCompromisedInstantaneously();
	   
   }   

	@After
	public void deleteModel() {
		Asset.allAssets.clear();
		AttackStep.allAttackSteps.clear();
		Defense.allDefenses.clear();
	}


}


