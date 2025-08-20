## Intro to Read Team

## What is Red Teaming?

As Joe Vest & James Tubberville said in their [book](https://redteam.guide/):
> Red Teaming is the process of using tactics, techniques and procedures (TTPs) to emulate a real-world threat, with the goal of measuring the effectiveness of the people, processes and technologies used to defend an environment.

### TTPs? What is it?

TTPs stand for Tactics, Techniques, and Procedures. It’s a concept widely used in the MITRE ATT&CK framework. Before talking about MITRE, we are going to define what is a TTP:

- Tactics:
That is what the attacker wants to achieve. Example: gain persistence, move laterally, exfiltrate data.

- Techniques:
The how it is achieved. Example: using stolen credentials for lateral movement, installing a service for persistence.

- Procedures:
The specific implementation details. Example: using psexec to execute processes on another machine, creating a scheduled task with a Cobalt Strike payload, or using Mimikatz to dump credentials.

### What about MITRE?

[MITRE ATT&CK framework](https://attack.mitre.org/) is a knowledge base of techniques, tactics, and procedures used by cybercriminals in recent years. Therefore, it is a framework that helps us understand how adversaries operate to compromise the security of our organization and to design the countermeasures, controls, and mitigations that we must implement in a preventive manner.

### Building the pieces, OPSEC

OPSEC is essential to ensure that penetration testing and security assessments are conducted effectively and safely, minimizing the risk of being discovered by the adversary and protecting the red team's sensitive information. Attack and avoid to be detected, that is THE mindset.


<img width="512" height="254" alt="imagen" src="https://github.com/user-attachments/assets/ad7c29ea-be75-4a83-817f-7d6cde711b6d" />


### Resources

If you want to know deeper how Red Team works in an OPSEC manner, you can get the [CRTO course by RastaMouse](https://www.zeropointsecurity.co.uk/course/red-team-ops). I highly recommend it!

<img width="1193" height="755" alt="imagen" src="https://github.com/user-attachments/assets/0ee08d78-d6d7-43bd-98ed-7741e0cfe7d8" />
