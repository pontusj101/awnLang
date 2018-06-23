package autoTests;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class GroupTest {

   @Test
   public void testGroup() {
	   
	   System.out.println("########## TESTS FOR GROUP ##########");
	   
	   System.out.println("~~~~~ NO DEFENSES IN PLACE / ALL DEFENSES IN PLACE ~~~~~");
	   
	   IAMaccount AdminIAMacct = new IAMaccount();
	   IAMaccount IAMacctOne = new IAMaccount();
	   IAMaccount IAMacctTwo = new IAMaccount();
	   Group group = new Group();
	
	   AdminIAMacct.addCreatedIAMgroups(group);
	   
	   group.addMemberIAMaccounts(IAMacctOne);
	   group.addPotentialMemberIAMaccounts(IAMacctTwo);
	   
	   Attacker attacker = new Attacker();
	   attacker.addAttackPoint(AdminIAMacct.compromise);
	   attacker.attack();
	   
	   AdminIAMacct.compromisedAccess.assertCompromisedInstantaneously();
	   IAMacctOne.deleteFromGroup.assertCompromisedInstantaneously();
	   IAMacctTwo.addToGroup.assertCompromisedInstantaneously();
	   
   }   

	@After
	public void deleteModel() {
		Asset.allAssets.clear();
		AttackStep.allAttackSteps.clear();
		Defense.allDefenses.clear();
	}


}


