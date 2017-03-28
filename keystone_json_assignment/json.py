#

import yaml

from oslo_config import cfg
from oslo_log import log

import keystone.conf
from keystone.assignment.backends import sql
from keystone.common import driver_hints
from keystone.common import manager
from keystone import exception

CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)

json_assignment_opts = [
    cfg.ListOpt('default_roles',
                default=['Member'],
                help='List of roles assigned by default to an LDAP user'),
    cfg.StrOpt('ldap_domain_name',
               default='ldap_users',
               help='Domain for the users in the JSON map.'
               ' Only supports one domain.'),
]
CONF.register_opts(json_assignment_opts, 'json_assignment')


class Assignment(sql.Assignment):

    def _setup_managers(self):
        self.resource_manager = manager.load_driver(
            'keystone.resource', CONF.resource.driver)
        self.id_mapping_manager = manager.load_driver(
            'keystone.identity.id_mapping', CONF.identity_mapping.driver)
        self.role_manager = manager.load_driver(
            'keystone.role', CONF.role.driver)

        # Look up the domain-specific identity driver and config
        domain_config = cfg.ConfigOpts()
        keystone.conf.configure(conf=domain_config)
        domain_name_filter = driver_hints.Hints()
        domain_name_filter.add_filter('name', self.domain_name)
        conf_dir = CONF.identity.domain_config_dir
        domain_config_file = "{}/keystone.{}.conf".format(
            conf_dir, self.domain_name)
        domain_config(args=[], project='keystone',
                      default_config_files=[domain_config_file],
                      default_config_dirs=[])
        self.identity_manager = manager.load_driver(
            'keystone.identity',
            domain_config.identity.driver,
            domain_config)

    def _get_role_id(self):
        role_name = CONF.json_assignment.default_roles[0]
        role_name_filter = driver_hints.Hints()
        role_name_filter.add_filter('name', role_name)
        return self.role_manager.list_roles(role_name_filter)[0]['id']

    def _get_user_id(self, user_name):
        user_id = self.identity_manager.get_user_by_name(
            user_name, self.domain_name)['id']
        user_id = self.id_mapping_manager.get_public_id({
            'domain_id': self.domain_id,
            'local_id': user_id,
            'entity_type': 'user'})
        return user_id

    def __init__(self):
        self.domain_name = CONF.json_assignment.ldap_domain_name
        self._setup_managers()
        self.domain_id = self.resource_manager.get_project_by_name(
            self.domain_name, domain_id=None)['id']
        self.role_id = self._get_role_id()

        with open('/etc/keystone/user-project-map.json', 'r') as f:
            userprojectmap = yaml.load(f)

        self.userprojectmap = {}
        projectidcache = {}
        for user, project in userprojectmap.items():
            projectids = {}
            projectid = None
            user_id = self._get_user_id(user)
            for projectname in project:
                try:
                    projectid = projectidcache[projectname]
                except KeyError:
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
            self.userprojectmap[user_id] = projectids

    def list_grant_role_ids(self, user_id=None, group_id=None,
                            domain_id=None, project_id=None,
                            inherited_to_projects=False):
        """List role ids for assignments/grants."""
        role_ids = super(Assignment, self).list_grant_role_ids(
            user_id=user_id, group_id=group_id,
            domain_id=domain_id, project_id=project_id,
            inherited_to_projects=inherited_to_projects)

        if user_id in self.userprojectmap and \
                project_id in self.userprojectmap[user_id]:
            role_ids.append(self.role_id)
        return role_ids

    def check_grant_role_id(self, role_id, user_id=None, group_id=None,
                            domain_id=None, project_id=None,
                            inherited_to_projects=False):
        """Check an assignment/grant role id.

        :raises keystone.exception.RoleAssignmentNotFound: If the role
            assignment doesn't exist.
        :returns: None or raises an exception if grant not found

        """
        try:
            super(Assignment, self).check_grant_role_id(
                    role_id, user_id=user_id, group_id=group_id,
                    domain_id=domain_id, project_id=project_id,
                    inherited_to_projects=inherited_to_projects)
        except keystone.exception.RoleAssignmentNotFound:
            if role_id != self.role_id:
                raise
            if user_id not in self.userprojectmap:
                raise
            if project_id not in self.userprojectmap[user_id]:
                raise

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

        for user_id, projects in self.userprojectmap.items():
            for project in projects:
                role_assignments.append({
                    'role_id': self.role_id,
                    'user_id': user_id,
                    'project_id': project
                })
        return role_assignments

    def add_role_to_user_and_project(self, user_id, tenant_id, role_id):
        msg = "This assignment backend is read-only."
        raise exception.NotImplemented(message=msg)

    def remove_role_from_user_and_project(self, user_id, tenant_id, role_id):
        msg = "This assignment backend is read-only."
        raise exception.NotImplemented(message=msg)

    def create_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        msg = "This assignment backend is read-only."
        raise exception.NotImplemented(message=msg)

    def delete_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        msg = "This assignment backend is read-only."
        raise exception.NotImplemented(message=msg)

    def delete_project_assignments(self, project_id):
        msg = "This assignment backend is read-only."
        raise exception.NotImplemented(message=msg)

    def delete_role_assignments(self, role_id):
        msg = "This assignment backend is read-only."
        raise exception.NotImplemented(message=msg)

    def delete_user_assignments(self, user_id):
        msg = "This assignment backend is read-only."
        raise exception.NotImplemented(message=msg)

    def delete_group_assignments(self, group_id):
        msg = "This assignment backend is read-only."
        raise exception.NotImplemented(message=msg)

    def delete_domain_assignments(self, domain_id):
        msg = "This assignment backend is read-only."
        raise exception.NotImplemented(message=msg)
