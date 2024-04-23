from pyad import adquery

def audit_kerberoasting(domain):
    # Connect to Active Directory
    ad_query = adquery.ADQuery()

    # Define query to retrieve user accounts with service principal names (SPNs)
    query = "(&(objectClass=user)(servicePrincipalName=*))"

    # Execute the query
    ad_query.execute_query(attributes=["sAMAccountName"], where_clause=query)

    # Display results
    print("Vulnerable User Accounts (with SPNs):")
    for row in ad_query.get_results():
        print(row["sAMAccountName"])

if __name__ == "__main__":
    # Define the target Active Directory domain
    domain = "jurassic.park"

    # Perform Kerberoasting vulnerability audit
    audit_kerberoasting(domain)
