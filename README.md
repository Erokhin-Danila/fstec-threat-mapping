**Description**

- This tool automates the process of transition from old threat models (linear numbering of UBI.001-UBI.227) to new ones (hierarchical numbering of X.Y.Z according to MOUBI-2021). 
The program uses a combined approach that includes text analysis, semantic classification, and heuristic rules based on official FSTEC documentation.


The program requires the **installation of dependencies** in the main project folder:
- pip install pandas openpyxl thefuzz python-Levenshtein


**Project structure:**
- Mapping.py - Main mapping program
- heuristic_rules.py - Heuristic classification rules
- mapping_result.xlsx - Example mapping result
- new_list.xlsx - New list of threats (X.Y.Z)
- old_list.xlsx - Old list of threats (UBI.001-UBI.227)

**Running:**

- python Mapping.py -old old_list.xlsx -new new_list.xlsx -not working mapping_result.xlsx -threshold 60
