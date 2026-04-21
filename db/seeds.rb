# This file should contain all the record creation needed to seed the database with its default values.
# The data can then be loaded with the rake db:seed (or created alongside the db with db:setup).

# Roles - these IDs are hardcoded in app/models/role.rb and must exist
[
  { id: 1, name: 'Student',  description: 'Student' },
  { id: 2, name: 'Tutor',    description: 'Tutor' },
  { id: 3, name: 'Convenor', description: 'Convenor' },
  { id: 4, name: 'Admin',    description: 'Admin' },
  { id: 5, name: 'Auditor',  description: 'Auditor' },
].each do |attrs|
  Role.find_or_create_by(id: attrs[:id]) do |r|
    r.name        = attrs[:name]
    r.description = attrs[:description]
  end
end
