def write(session):
    session.run("MERGE (e:Endpoint {id: $id})", id="fixture")
