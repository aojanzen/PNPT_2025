# Logical Active Directory Components

The **AD DS Schema** can be considered a rolebook or **blueprint**. It defines
every type of object that can be stored in our directory as well as rules for
object creation and configuration. There are different types of objects: class
objects for entities such as users or ressources and attribute objects that store
information, e.g. a display name.



<img src="./images/LogicalADComponents_1.png" alt="Logical Active Discovery Components 1" width="800"/>



**Domains** are used to group and organize the objects in a network. Their names
have structures like `contoso.com` used in the example below, but the ending can
also be different like, e.g. `.local`, `.banana` or so. The domains are controlled
by the previously discussed domain controller. The domain is a boundary for
applying policies. In the course we will only use a single domain,
`MARVEL.local`, but there can be situations where we encounter more than one
domain. 



<img src="./images/LogicalADComponents_2.png" alt="Logical Active Discovery Components 2" width="800"/>



A hierarchy of domains is organized in a **tree** with a parent domain, e.g.
`contoso.com` and several children domains, e.g. `emea.contoso.com` and
`na.contoso.com`.



<img src="./images/LogicalADComponents_3.png" alt="Logical Active Discovery Components 3" width="800"/>



A collection of trees is called a **forest**. Most of the time, internal
pentests are executed against a single domain. Jumping from one domain to
another is a bit more advanced and not covered in this course. Since forests
share enterprise and schema administrators, elevating to one of these accounts
may allow one to cross domain boundaries, while domain admins are not
necessarily also enterprise or schema admins and hence may not be able to cross
domain boundaries.



<img src="./images/LogicalADComponents_4.png" alt="Logical Active Discovery Components 4" width="800"/>



**Organizational Units** are containers that are used to organize objects, e.g.
users, computers, other OUs, etc. One can also group objects into OUs and then
apply a common policy to the objects in the OU.



<img src="./images/LogicalADComponents_5.png" alt="Logical Active Discovery Components 5" width="800"/>



**Trust** can be directional (i.e., from a trusting to a trusted domain) or
transitive.



<img src="./images/LogicalADComponents_6.png" alt="Logical Active Discovery Components 6" width="800"/>



**Objects** live within an organizational unit and can be all sorts of things,
such as users, computers, printers, etc.



<img src="./images/LogicalADComponents_7.png" alt="Logical Active Discovery Components 7" width="800"/>



<!--
span style="color:green;font-weight:700;font-size:20px">
markdown color font styles
</span
-->
