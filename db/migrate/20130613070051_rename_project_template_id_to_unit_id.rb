class RenameProjectTemplateIdToUnitId < ActiveRecord::Migration[4.2]
  def change
    rename_column :teams, :project_template_id, :unit_id if column_exists?(:teams, :project_template_id)
    rename_column :task_templates, :project_template_id, :unit_id if column_exists?(:task_templates, :project_template_id)
    rename_column :project_convenors, :project_template_id, :unit_id if column_exists?(:project_convenors, :project_template_id)
    rename_column :projects, :project_template_id, :unit_id if column_exists?(:projects, :project_template_id)

    rename_index :projects, "index_projects_on_project_template_id", "index_projects_on_unit_id" if index_exists?(:projects, :unit_id, name: "index_projects_on_project_template_id")
    rename_index :task_templates, "index_task_templates_on_project_template_id", "index_task_templates_on_unit_id" if index_exists?(:task_templates, :unit_id, name: "index_task_templates_on_project_template_id")
    rename_index :teams, "index_teams_on_project_template_id", "index_teams_on_unit_id" if index_exists?(:teams, :unit_id, name: "index_teams_on_project_template_id")
  end
end
