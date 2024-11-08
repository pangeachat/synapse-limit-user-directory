def main():
    import argparse
    from importlib.metadata import PackageNotFoundError, version

    parser = argparse.ArgumentParser(description="A simple version checker.")

    parser.add_argument(
        "--version",
        "-v",
        action="store_true",
        help="Display the version",
    )

    args = parser.parse_args()

    if args.version:
        try:
            project_version = version("synapse_limit_user_directory")
            print(f"Version {project_version}")
        except PackageNotFoundError:
            print(
                "Package not found. Make sure it's installed and pyproject.toml is properly configured."
            )


if __name__ == "__main__":
    main()
