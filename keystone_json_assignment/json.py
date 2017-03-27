#

import yaml

from oslo_config import cfg
from oslo_log import log

import keystone.conf
from keystone.assignment.backends import sql
from keystone.common import dependency
from keystone.common import driver_hints
from keystone.common import manager
from keystone import exception
from keystone import resource

CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)

json_assignment_opts = [
    cfg.ListOpt('default_roles',
                default=['Member'],
                help='List of roles assigned by default to an LDAP user'),
    cfg.StrOpt('ldap_domain_name',
                default='ldap_users',
                help='Domain for the users in the JSON map. Only supports one domain.'),
]
CONF.register_opts(json_assignment_opts, 'json_assignment')

class Assignment(sql.Assignment):

    def __init__(self):
        self.resource_manager = manager.load_driver('keystone.resource', CONF.resource.driver)
        domain_config = { 'cfg': cfg.ConfigOpts() }
        keystone.conf.configure(conf=domain_config['cfg'])
        self.domain_name = CONF.json_assignment.ldap_domain_name
        domain_name_filter= driver_hints.Hints()
        domain_name_filter.add_filter('name', self.domain_name)
        self.domain_id = self.resource_manager.get_project_by_name(self.domain_name, domain_id=None)['id']
        domain_config_file = "/etc/keystone/domains/keystone.%s.conf" % self.domain_name
        domain_config['cfg'](args=[], project='keystone', default_config_files=[domain_config_file], default_config_dirs=[])
        self.identity_manager = manager.load_driver('keystone.identity', domain_config['cfg'].identity.driver, domain_config['cfg'])
        self.id_mapping_manager = manager.load_driver('keystone.identity.id_mapping', CONF.identity_mapping.driver)
        self.role_manager = manager.load_driver('keystone.role', CONF.role.driver)
        role_name_filter = driver_hints.Hints()
        role_name_filter.add_filter('name', CONF.json_assignment.default_roles[0])
        self.role_id = self.role_manager.list_roles(role_name_filter)[0]['id']
        with open('/etc/keystone/user-project-map.json', 'r') as f:
            self.userprojectmap = yaml.load(f)
        projectidcache = {}
        for user in self.userprojectmap:
            projectids = {}
            projectid = None
            for projectname in self.userprojectmap[user]:
                try:
                    projectid = projectidcache[projectname]
                except:
                    # cache miss - need to fetch from DB
                    try:
                        project = self.resource_manager.get_project_by_name(
                            projectname, CONF.identity.default_domain_id)
                        projectid = project['id']
                        projectidcache[projectname] = project['id']
                    except Exception as e:
                        print(e)
                if projectid:
                    projectids[projectid] = 1
            self.userprojectmap[user] = projectids

    def list_grant_role_ids(self, user_id=None, group_id=None,
                            domain_id=None, project_id=None,
                            inherited_to_projects=False):
        """List role ids for assignments/grants."""
        raise exception.NotImplemented(message="List Grant Role IDs not implemented yet")

    def check_grant_role_id(self, role_id, user_id=None, group_id=None,
                            domain_id=None, project_id=None,
                            inherited_to_projects=False):
        """Check an assignment/grant role id.

        :raises keystone.exception.RoleAssignmentNotFound: If the role
            assignment doesn't exist.
        :returns: None or raises an exception if grant not found

        """
        raise exception.NotImplemented(message="Check Grant Role ID not implemented yet")

    def list_role_assignments(self, role_id=None,
                              user_id=None, group_ids=None,
                              domain_id=None, project_ids=None,
                              inherited_to_projects=None):
        """Return a list of role assignments for actors on targets.

        Available parameters represent values in which the returned role
        assignments attributes need to be filtered on.

        """
        role_assignments = super(Assignment, self).list_role_assignments(
             role_id=role_id, user_id=user_id, group_ids=group_ids,
             domain_id=domain_id, project_ids=project_ids,
             inherited_to_projects=inherited_to_projects)

        for user, projects in self.userprojectmap.items():
            user_id = self.identity_manager.get_user_by_name(user, self.domain_name)['id']
            user_id = self.id_mapping_manager.get_public_id({'domain_id': self.domain_id, 'local_id': user_id, 'entity_type': 'user' })
            for project in projects:
                role_assignments.append({'role_id': self.role_id, 'user_id': user_id, 'project_id': project})

        return role_assignments

    def add_role_to_user_and_project(self, user_id, tenant_id, role_id):
        raise exception.NotImplemented(message="This assignment backend is read-only.")

    def remove_role_from_user_and_project(self, user_id, tenant_id, role_id):
        raise exception.NotImplemented(message="This assignment backend is read-only.")

    def create_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        raise exception.NotImplemented(message="This assignment backend is read-only.")

    def delete_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        raise exception.NotImplemented(message="This assignment backend is read-only.")

    def delete_project_assignments(self, project_id):
        raise exception.NotImplemented(message="This assignment backend is read-only.")

    def delete_role_assignments(self, role_id):
        raise exception.NotImplemented(message="This assignment backend is read-only.")

    def delete_user_assignments(self, user_id):
        raise exception.NotImplemented(message="This assignment backend is read-only.")

    def delete_group_assignments(self, group_id):
        raise exception.NotImplemented(message="This assignment backend is read-only.")

    def delete_domain_assignments(self, domain_id):
        raise exception.NotImplemented(message="This assignment backend is read-only.")
