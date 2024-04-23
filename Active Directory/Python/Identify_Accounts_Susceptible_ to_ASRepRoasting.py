from pyad import adquery

def audit_asreproast(domain):
    # Connect to Active Directory
    ad_query = adquery.ADQuery()

    # Define query to retrieve user accounts with pre-authentication disabled
    query = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"

    # Execute the query
    ad_query.execute_query(attributes=["sAMAccountName"], where_clause=query)

    # Display results
    print("Vulnerable User Accounts:")
    for row in ad_query.get_results():
        print(row["sAMAccountName"])

if __name__ == "__main__":
    # Define the target Active Directory domain
    domain = "jurassic.park"

    # Perform ASRepRoasting vulnerability audit
    audit_asreproast(domain)
