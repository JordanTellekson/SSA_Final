# Phishing Threat Model 

## Overview 
This threat model outlines how phishing attacks are carried out, the techniques attackers use to bypass detection, and how the system can identify and mitigate these threats. The goal is to help developers understand attacker behavior and build more effecetive defenses 

## Threat Actors 
- Cybercriminals targeting user credentials and financial data  
- Automated phishing kits and bot-driven campaigns  
- Organized phishing groups  

## Attack Flow
1. Domain creation (lookalike or new domains)  
2. Hosting phishing pages  
3. Sending links via email or messages  
4. User clicks link and enters information  
5. Attacker collects and uses the data  

## Evasion Techniques
- Typosquatting and lookalike domains  
- HTTPS used to appear safe  
- URL obfuscation  
- Redirect chains  
- Copying real website designs  

## Detection Strategies
- Check domain age and WHOIS data  
- Detect suspicious or lookalike URLs  
- Analyze URL structure  
- Monitor redirects  
- Use blacklists and reputation systems  

## Mitigation Strategies
- Block suspicious domains  
- Warn users about risky links  
- Use multi-factor authentication  
- Continuously update detection rules  

## Conclusion
Understanding phishing behavior allows developers to build systems that detect and reduce threats more effectively.
